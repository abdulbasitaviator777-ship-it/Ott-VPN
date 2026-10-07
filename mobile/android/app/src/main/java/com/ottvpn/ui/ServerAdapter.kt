package com.ottvpn.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.ottvpn.R
import com.ottvpn.api.ServerInfo

/**
 * RecyclerView adapter for displaying VPN server list.
 */
class ServerAdapter(
    private var servers: List<ServerInfo>,
    private val onItemClick: (ServerInfo) -> Unit
) : RecyclerView.Adapter<ServerAdapter.ServerViewHolder>() {

    inner class ServerViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val nameText: TextView = itemView.findViewById(R.id.server_name)
        private val locationText: TextView = itemView.findViewById(R.id.server_location)
        private val latencyText: TextView = itemView.findViewById(R.id.server_latency)
        private val loadText: TextView = itemView.findViewById(R.id.server_load)

        fun bind(server: ServerInfo) {
            nameText.text = "${server.city}, ${server.region ?: ""}"
            locationText.text = server.country
            latencyText.text = server.latencyMs?.let { "${it.toInt()} ms" } ?: "—"
            loadText.text = server.loadPercent?.let { "${it.toInt()}%" } ?: "—"
            itemView.setOnClickListener { onItemClick(server) }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ServerViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_server, parent, false)
        return ServerViewHolder(view)
    }

    override fun onBindViewHolder(holder: ServerViewHolder, position: Int) {
        holder.bind(servers[position])
    }

    override fun getItemCount(): Int = servers.size

    fun updateServers(newServers: List<ServerInfo>) {
        servers = newServers
        notifyDataSetChanged()
    }
}
