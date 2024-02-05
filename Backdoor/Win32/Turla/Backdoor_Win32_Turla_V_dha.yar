
rule Backdoor_Win32_Turla_V_dha{
	meta:
		description = "Backdoor:Win32/Turla.V!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 29 00 00 01 00 "
		
	strings :
		$a_80_0 = {00 63 6f 6e 66 69 67 5f 72 65 61 64 5f 75 69 6e 74 33 32 } //  01 00 
		$a_80_1 = {00 63 6f 64 65 5f 72 65 73 75 6c 74 5f 74 62 6c } //  01 00 
		$a_80_2 = {00 6d 32 62 5f 72 61 77 } //  01 00 
		$a_80_3 = {00 71 6d 5f 72 6d 5f 6c 69 73 74 } //  01 00 
		$a_80_4 = {00 72 6b 5f 70 63 61 70 5f 63 6d 64 } //  01 00 
		$a_80_5 = {00 72 65 61 64 5f 70 65 65 72 5f 6e 66 6f } //  01 00 
		$a_80_6 = {00 73 6e 61 6b 65 5f 61 6c 6c 6f 63 } //  01 00 
		$a_80_7 = {00 73 6e 61 6b 65 5f 66 72 65 65 } //  01 00 
		$a_80_8 = {00 73 6e 61 6b 65 5f 6d 6f 64 75 6c 65 73 5f 63 6f 6d 6d 61 6e 64 } //  01 00 
		$a_80_9 = {00 74 5f 73 65 74 6f 70 74 62 69 6e } //  01 00 
		$a_80_10 = {00 74 5f 73 65 74 6f 70 74 6c 69 73 74 } //  01 00 
		$a_80_11 = {00 74 63 5f 63 61 6e 63 65 6c } //  01 00 
		$a_80_12 = {00 74 63 5f 66 72 65 65 5f 64 61 74 61 } //  01 00 
		$a_80_13 = {00 74 63 5f 67 65 74 5f 72 65 70 6c 79 } //  01 00 
		$a_80_14 = {00 74 63 5f 72 65 61 64 5f 72 65 71 75 65 73 74 5f 70 69 70 65 } //  01 00 
		$a_80_15 = {00 74 63 5f 73 65 6e 64 5f 72 65 71 75 65 73 74 5f 62 75 66 73 } //  01 00 
		$a_80_16 = {00 74 63 5f 73 6f 63 6b 65 74 } //  01 00 
		$a_80_17 = {00 74 72 5f 61 6c 6c 6f 63 } //  01 00 
		$a_80_18 = {00 74 72 5f 67 65 74 5f 63 61 6c 6c 62 61 63 6b 73 } //  01 00 
		$a_80_19 = {00 74 72 5f 77 72 69 74 65 5f 70 69 70 65 } //  01 00 
		$a_80_20 = {00 77 72 69 74 65 5f 70 65 65 72 5f 6e 66 6f } //  01 00 
		$a_80_21 = {00 69 6e 6a 5f 73 6e 61 6b 65 5f } //  01 00 
		$a_80_22 = {00 72 6b 63 74 6c 5f } //  01 00 
		$a_80_23 = {00 69 6e 6a 5f 73 65 72 76 69 63 65 73 5f } //  02 00 
		$a_80_24 = {2e 64 6c 6c 00 4d 6f 64 75 6c 65 43 6f 6d 6d 61 6e 64 00 4d 6f 64 75 6c 65 53 74 61 72 74 00 4d 6f 64 75 6c 65 53 74 6f 70 00 } //.dll  01 00 
		$a_80_25 = {6e 6f 5f 73 65 72 76 65 72 5f 68 69 6a 61 63 6b } //no_server_hijack  01 00 
		$a_80_26 = {72 65 6c 69 61 62 6c 65 5f 6e 5f 74 72 69 65 73 } //reliable_n_tries  01 00 
		$a_80_27 = {66 72 61 67 5f 6e 6f 5f 73 63 72 61 6d 62 6c 69 6e 67 } //frag_no_scrambling  01 00 
		$a_80_28 = {72 63 76 5f 62 75 66 3d 25 64 25 63 } //rcv_buf=%d%c  01 00 
		$a_80_29 = {00 74 61 69 63 68 69 6e } //  01 00 
		$a_80_30 = {00 77 69 6e 69 6e 65 74 5f 61 63 74 69 76 61 74 65 } //  02 00 
		$a_80_31 = {09 74 69 3d 25 75 09 73 74 3d 25 64 09 73 6f 3d 25 78 09 } //	ti=%u	st=%d	so=%x	  02 00 
		$a_80_32 = {3d 71 75 65 72 79 26 69 64 3d 25 75 3a 25 75 3a 25 75 3a 25 75 26 73 65 72 76 3d 25 73 26 6c 61 6e 67 3d 65 6e 26 71 3d 25 75 2d 25 75 26 64 61 74 65 3d 25 73 } //=query&id=%u:%u:%u:%u&serv=%s&lang=en&q=%u-%u&date=%s  01 00 
		$a_80_33 = {53 54 7c 43 61 72 62 6f 6e 20 76 } //ST|Carbon v  01 00 
		$a_80_34 = {4f 50 45 52 7c 57 72 6f 6e 67 } //OPER|Wrong  01 00 
		$a_80_35 = {4f 50 45 52 7c 53 6e 69 66 66 65 72 } //OPER|Sniffer  01 00 
		$a_80_36 = {6d 73 74 6f 6b 20 25 73 } //mstok %s  01 00 
		$a_80_37 = {23 23 6d 73 74 20 25 73 20 25 64 } //##mst %s %d  01 00 
		$a_80_38 = {25 73 23 25 73 2e 65 78 65 23 25 73 23 23 59 } //%s#%s.exe#%s##Y  01 00 
		$a_80_39 = {23 23 69 73 73 6d 20 70 72 73 21 } //##issm prs!  01 00 
		$a_80_40 = {23 23 64 6b 20 25 53 20 30 78 25 30 38 78 } //##dk %S 0x%08x  00 00 
	condition:
		any of ($a_*)
 
}