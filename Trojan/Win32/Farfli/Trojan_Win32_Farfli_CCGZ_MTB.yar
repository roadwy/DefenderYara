
rule Trojan_Win32_Farfli_CCGZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CCGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 33 ff 8a 87 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 47 6a 00 ff d3 b8 ?? ?? ?? ?? f7 e6 c1 ea 02 8d 0c 92 8b d6 2b d1 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}