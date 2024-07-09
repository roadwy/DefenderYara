
rule Trojan_Win32_lokibot_RPC_MTB{
	meta:
		description = "Trojan:Win32/lokibot.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 10 8b 55 94 8a c3 32 45 93 85 c9 75 } //1
		$a_03_1 = {ff 45 80 8b 45 80 3b 45 0c 0f 8c ?? ?? ?? ?? 8b 4d f8 5f 5e 33 cd 5b e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}