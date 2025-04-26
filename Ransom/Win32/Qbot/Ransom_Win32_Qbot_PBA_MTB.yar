
rule Ransom_Win32_Qbot_PBA_MTB{
	meta:
		description = "Ransom:Win32/Qbot.PBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 40 eb 00 89 45 ?? 8b 45 ?? 3b 45 ?? 73 05 e9 } //1
		$a_03_1 = {8b 45 fc 0f b6 44 10 ?? 33 c8 66 3b ed 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}