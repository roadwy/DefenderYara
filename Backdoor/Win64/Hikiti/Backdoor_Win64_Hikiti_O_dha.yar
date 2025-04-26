
rule Backdoor_Win64_Hikiti_O_dha{
	meta:
		description = "Backdoor:Win64/Hikiti.O!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 32 c0 88 01 48 8d 41 01 4c 8b c8 48 8b d0 49 f7 d9 44 30 02 74 10 48 ff c2 49 8d 0c 11 48 81 f9 03 01 00 00 7c eb f3 c3 } //1
		$a_03_1 = {48 8b d3 48 8b c8 ff 15 ?? ?? ?? ?? 48 85 c0 74 02 ff d0 48 8b 4d ?? 48 33 cc e8 ?? ?? ?? ?? 48 8b 5c 24 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}