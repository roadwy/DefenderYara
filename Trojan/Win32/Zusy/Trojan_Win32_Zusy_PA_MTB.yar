
rule Trojan_Win32_Zusy_PA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 69 6f 74 63 6c 69 65 6e 74 } //1 riotclient
		$a_01_1 = {fe c3 8a 04 1e 02 d0 86 04 16 88 04 1e 02 04 16 8a 04 06 30 07 47 49 75 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3) >=4
 
}