
rule Trojan_Win32_Gandcrab_DHA_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.DHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 45 f4 03 45 fc 0f be 18 e8 ?? ?? ?? ?? 33 d8 8b 4d f4 03 4d fc 88 19 eb } //1
		$a_02_1 = {55 8b ec a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 5d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}