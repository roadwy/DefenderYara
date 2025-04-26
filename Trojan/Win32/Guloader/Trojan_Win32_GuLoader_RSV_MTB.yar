
rule Trojan_Win32_GuLoader_RSV_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {64 69 67 74 63 79 6b 6c 65 6e 73 20 61 61 72 72 69 6e 67 65 6e 65 } //1 digtcyklens aarringene
		$a_81_1 = {66 69 6c 73 74 69 20 6c 61 67 67 61 72 64 73 2e 65 78 65 } //1 filsti laggards.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}