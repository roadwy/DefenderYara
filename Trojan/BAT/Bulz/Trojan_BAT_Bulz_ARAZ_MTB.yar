
rule Trojan_BAT_Bulz_ARAZ_MTB{
	meta:
		description = "Trojan:BAT/Bulz.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 63 36 33 32 66 64 39 2d 31 36 39 34 2d 34 66 34 61 2d 39 62 66 66 2d 66 32 30 36 30 30 65 33 37 39 38 31 } //2 ec632fd9-1694-4f4a-9bff-f20600e37981
		$a_01_1 = {73 69 68 6f 73 74 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 sihost.Resources.resources
		$a_01_2 = {5c 73 69 68 6f 73 74 2e 70 64 62 } //2 \sihost.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}