
rule Trojan_Win32_Zdowbot_NZ_MTB{
	meta:
		description = "Trojan:Win32/Zdowbot.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 8d 4e 40 51 83 c2 40 52 e8 ?? ?? ?? ?? 83 c4 0c 33 c0 33 db 66 3b 47 06 } //3
		$a_03_1 = {03 ce 51 52 e8 ?? ?? ?? ?? 0f b7 47 06 43 83 c4 0c 3b d8 7c } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}