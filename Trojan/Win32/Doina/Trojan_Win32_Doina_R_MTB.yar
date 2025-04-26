
rule Trojan_Win32_Doina_R_MTB{
	meta:
		description = "Trojan:Win32/Doina.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ac 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 32 02 aa 42 49 } //1
		$a_03_1 = {ac 30 d0 aa c1 ca 08 49 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 85 c9 75 e7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}