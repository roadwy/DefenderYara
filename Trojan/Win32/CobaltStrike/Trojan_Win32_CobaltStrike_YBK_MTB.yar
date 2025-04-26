
rule Trojan_Win32_CobaltStrike_YBK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.YBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f0 89 75 ec 01 ca 0f b6 04 10 32 04 13 8b 5d d8 88 44 33 ff 89 d9 } //10
		$a_01_1 = {89 ce 8b 4d ec 8b 5d d4 0f b6 04 10 83 c3 02 32 44 17 01 88 04 0e 8b 75 d0 83 c1 02 } //2
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2) >=12
 
}