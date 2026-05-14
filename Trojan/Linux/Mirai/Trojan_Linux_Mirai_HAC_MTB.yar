
rule Trojan_Linux_Mirai_HAC_MTB{
	meta:
		description = "Trojan:Linux/Mirai.HAC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 74 30 74 61 6c 63 30 6e } //30
		$a_01_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 46 41 53 54 43 41 54 } //5 /bin/busybox FASTCAT
		$a_01_2 = {5b 25 73 3a 25 64 5d 20 73 65 6e 74 20 70 69 6e 67 20 74 6f 20 74 68 65 20 63 6e 63 } //5 [%s:%d] sent ping to the cnc
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=35
 
}