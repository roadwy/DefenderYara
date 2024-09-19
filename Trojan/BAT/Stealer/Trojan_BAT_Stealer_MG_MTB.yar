
rule Trojan_BAT_Stealer_MG_MTB{
	meta:
		description = "Trojan:BAT/Stealer.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {72 63 48 61 63 6b } //1 rcHack
		$a_00_1 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 DisableRealtimeMonitoring
		$a_01_2 = {52 00 65 00 6d 00 61 00 69 00 6e 00 69 00 6e 00 67 00 20 00 74 00 69 00 6d 00 65 00 } //1 Remaining time
		$a_00_3 = {44 69 73 63 6f 72 64 43 6f 6d 6d 61 6e 64 } //1 DiscordCommand
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}