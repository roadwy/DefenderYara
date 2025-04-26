
rule Trojan_Win32_DarkCloud_MBIP_MTB{
	meta:
		description = "Trojan:Win32/DarkCloud.MBIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 b5 4c 02 ce 82 e6 1d 87 19 44 52 33 d7 ec 1c 59 06 0e } //1
		$a_01_1 = {f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 ac 32 40 00 ac 32 40 00 2c 31 40 00 78 00 00 00 80 00 00 00 89 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}