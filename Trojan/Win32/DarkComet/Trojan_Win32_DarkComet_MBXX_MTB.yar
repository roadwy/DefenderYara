
rule Trojan_Win32_DarkComet_MBXX_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.MBXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 25 40 00 98 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 28 11 40 00 28 11 40 00 ec 10 40 00 78 00 00 00 80 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}