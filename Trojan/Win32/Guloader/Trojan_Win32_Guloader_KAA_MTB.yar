
rule Trojan_Win32_Guloader_KAA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 45 ec 06 47 48 b0 bd 82 83 bc ff e9 ea f4 fe d3 d4 e8 ff ba bc db fe } //1
		$a_01_1 = {48 46 e3 0e 4a 47 9e ed 94 93 c2 ff c4 c4 de } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}