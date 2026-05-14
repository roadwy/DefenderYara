
rule Trojan_Win32_PulsarRAT_PGPR_MTB{
	meta:
		description = "Trojan:Win32/PulsarRAT.PGPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 4d 08 01 c1 8b 45 fc 8b 55 08 01 c2 0f be 02 40 83 f0 69 88 01 eb da } //5
		$a_03_1 = {41 50 50 44 41 54 41 00 5c 4d 69 63 72 6f 73 6f 66 74 5c 55 70 64 61 74 65 2e 63 70 6c 00 46 49 4c 45 52 45 53 5f 30 00 25 73 5c [0-1f] 2e 65 78 65 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}