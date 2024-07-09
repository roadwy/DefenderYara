
rule Trojan_Win32_Doina_S_MTB{
	meta:
		description = "Trojan:Win32/Doina.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ac 50 58 32 02 aa 42 49 85 c9 75 ed [0-35] ac 30 d0 aa c1 ca 08 49 85 c9 75 f4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}