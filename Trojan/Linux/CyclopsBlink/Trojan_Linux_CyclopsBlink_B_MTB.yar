
rule Trojan_Linux_CyclopsBlink_B_MTB{
	meta:
		description = "Trojan:Linux/CyclopsBlink.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 70 65 6e 64 69 6e 67 2f 62 69 6e 2f 69 6e 73 74 61 6c 6c 5f 75 70 67 72 61 64 65 64 } //1 /pending/bin/install_upgraded
		$a_00_1 = {2f 70 65 6e 64 69 6e 67 2f 62 69 6e 2f 53 35 31 61 72 6d 6c 65 64 } //1 /pending/bin/S51armled
		$a_00_2 = {2f 70 65 6e 64 69 6e 67 2f 62 69 6e 2f 62 75 73 79 62 6f 78 2d 72 65 6c } //1 /pending/bin/busybox-rel
		$a_00_3 = {69 6e 73 74 61 6c 6c 5f 70 61 79 6c 6f 61 64 } //1 install_payload
		$a_00_4 = {2f 70 65 6e 64 69 6e 67 2f 57 47 55 70 67 72 61 64 65 2d 64 6c 2e 6e 65 77 } //1 /pending/WGUpgrade-dl.new
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}