
rule Trojan_Win32_Copak_GIB_MTB{
	meta:
		description = "Trojan:Win32/Copak.GIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 ff 42 e8 ?? ?? ?? ?? 52 5f 31 30 21 d7 40 81 c7 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 39 c8 75 } //10
		$a_03_1 = {09 df 83 ec 04 c7 04 24 ?? ?? ?? ?? 58 e8 ?? ?? ?? ?? 31 02 81 c2 01 00 00 00 01 db 39 f2 75 ?? 89 df } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}