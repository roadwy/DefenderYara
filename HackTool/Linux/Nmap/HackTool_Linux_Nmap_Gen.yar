
rule HackTool_Linux_Nmap_Gen{
	meta:
		description = "HackTool:Linux/Nmap.Gen,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_80_0 = {4e 6d 61 70 20 73 63 61 6e 20 72 65 70 6f 72 74 20 66 6f 72 20 25 73 } //Nmap scan report for %s  1
		$a_80_1 = {53 6f 6d 65 20 70 72 6f 62 65 73 20 66 61 69 6c 65 64 20 74 6f 20 73 65 6e 64 20 73 6f 20 72 65 73 75 6c 74 73 20 69 6e 63 6f 6d 70 6c 65 74 65 } //Some probes failed to send so results incomplete  1
		$a_80_2 = {72 65 63 65 69 76 65 20 55 44 50 20 72 65 73 70 6f 6e 73 65 2e 20 50 6c 65 61 73 65 20 74 72 79 20 61 67 61 69 6e 20 77 69 74 68 20 2d 73 53 55 } //receive UDP response. Please try again with -sSU  1
		$a_80_3 = {46 69 6e 67 65 72 50 72 69 6e 74 52 65 73 75 6c 74 73 49 50 76 36 } //FingerPrintResultsIPv6  1
		$a_80_4 = {53 74 61 72 74 69 6e 67 20 49 50 76 36 20 4f 53 20 53 63 61 6e 2e 2e 2e } //Starting IPv6 OS Scan...  1
		$a_80_5 = {55 6e 61 62 6c 65 20 74 6f 20 6f 62 74 61 69 6e 20 61 6e 20 4e 73 6f 63 6b 20 70 6f 6f 6c } //Unable to obtain an Nsock pool  1
		$a_80_6 = {75 64 70 2d 3e 70 72 6f 74 6f 63 6f 6c 5f 69 64 28 29 20 3d 3d 20 48 45 41 44 45 52 5f 54 59 50 45 5f 55 44 50 } //udp->protocol_id() == HEADER_TYPE_UDP  1
		$a_80_7 = {55 6e 65 78 70 65 63 74 65 64 20 4e 73 6f 63 6b 20 65 76 65 6e 74 20 69 6e 20 72 65 73 70 6f 6e 73 65 5f 72 65 63 65 70 74 69 6f 6e 5f 68 61 6e 64 6c 65 72 28 29 } //Unexpected Nsock event in response_reception_handler()  1
		$a_80_8 = {72 65 73 70 6f 6e 73 65 5f 72 65 63 65 70 74 69 6f 6e 5f 68 61 6e 64 6c 65 72 28 29 3a 20 55 6e 6b 6e 6f 77 6e 20 73 74 61 74 75 73 20 63 6f 64 65 20 25 64 } //response_reception_handler(): Unknown status code %d  1
		$a_80_9 = {5b 25 73 5d 20 52 65 74 72 61 6e 73 6d 69 74 74 69 6e 67 20 74 69 6d 65 64 20 70 72 6f 62 65 73 20 28 72 63 76 64 5f 62 65 66 6f 72 65 3d 25 75 2c 20 72 63 76 64 5f 6e 6f 77 3d 25 75 20 74 69 6d } //[%s] Retransmitting timed probes (rcvd_before=%u, rcvd_now=%u tim  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=5
 
}