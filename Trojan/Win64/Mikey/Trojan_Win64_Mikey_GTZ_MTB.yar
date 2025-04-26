
rule Trojan_Win64_Mikey_GTZ_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {f3 8b ec 60 97 30 68 ?? 63 fb 1c 61 0c ce 00 e1 e2 ?? 6a 85 30 00 } //10
		$a_03_1 = {30 24 73 1c f6 2b 31 03 f1 31 1f 09 d7 92 ?? fe 64 bc ?? ?? ?? ?? 21 cb 20 e2 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}