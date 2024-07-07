
rule Trojan_Win32_LuoBot_RPY_MTB{
	meta:
		description = "Trojan:Win32/LuoBot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 f7 89 f0 31 db 81 c7 90 01 02 00 00 81 2e 90 01 04 83 c6 04 39 fe 7c f3 90 00 } //1
		$a_02_1 = {89 f7 31 c0 40 89 f0 81 c7 90 01 02 00 00 81 2e 90 01 04 83 c6 04 39 fe 7c f3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}