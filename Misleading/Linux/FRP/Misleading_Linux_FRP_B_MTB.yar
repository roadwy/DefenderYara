
rule Misleading_Linux_FRP_B_MTB{
	meta:
		description = "Misleading:Linux/FRP.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 66 61 74 65 64 69 65 72 2f 66 72 70 2f } //01 00  /fatedier/frp/
		$a_01_1 = {2f 73 79 73 2f 6b 65 72 6e 65 6c 2f 6d 6d 2f 74 72 61 6e 73 70 61 72 65 6e 74 5f 68 75 67 65 70 61 67 65 2f 68 70 61 67 65 5f 70 6d 64 5f 73 69 7a 65 } //01 00  /sys/kernel/mm/transparent_hugepage/hpage_pmd_size
		$a_01_2 = {4b 65 79 4c 6f 67 57 72 69 74 65 72 } //00 00  KeyLogWriter
	condition:
		any of ($a_*)
 
}