
rule Ransom_Win64_FunkSec_CCJT_MTB{
	meta:
		description = "Ransom:Win64/FunkSec.CCJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 75 6e 6b 73 65 63 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 20 2f 74 72 20 22 22 20 2f 73 63 20 6f 6e 73 74 61 72 74 } //2 funksecschtasks /create /tn  /tr "" /sc onstart
		$a_01_1 = {53 63 68 65 64 75 6c 65 64 20 74 61 73 6b 20 63 72 65 61 74 65 64 20 74 6f 20 72 75 6e 20 72 61 6e 73 6f 6d 77 61 72 65 20 61 74 20 73 74 61 72 74 75 70 2e } //1 Scheduled task created to run ransomware at startup.
		$a_01_2 = {53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //1 Set-MpPreference -DisableRealtimeMonitoring
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}