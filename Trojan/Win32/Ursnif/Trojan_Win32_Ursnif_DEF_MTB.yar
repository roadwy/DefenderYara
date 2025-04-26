
rule Trojan_Win32_Ursnif_DEF_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a d3 83 c4 30 0f be 0c 01 89 4d 14 0a 5d 14 f6 d2 f6 d1 0a d1 22 d3 88 10 } //1
		$a_81_1 = {31 32 34 33 36 35 53 44 53 43 7a 73 66 64 66 67 72 53 46 64 67 68 66 64 67 68 66 67 68 63 76 46 53 63 7a 73 64 } //1 124365SDSCzsfdfgrSFdghfdghfghcvFSczsd
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}