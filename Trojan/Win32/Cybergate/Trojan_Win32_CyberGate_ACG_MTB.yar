
rule Trojan_Win32_CyberGate_ACG_MTB{
	meta:
		description = "Trojan:Win32/CyberGate.ACG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 33 d2 89 55 e8 89 55 ec 8b d8 33 c0 55 68 5e 6c 00 14 64 ff 30 64 89 20 8d 45 f0 50 e8 } //2
		$a_03_1 = {ba 60 68 04 14 b8 01 00 00 80 e8 ?? ?? ?? ?? 68 74 68 04 14 6a 00 6a 00 e8 9f e8 ?? ?? ?? ?? 38 ac 04 14 89 02 b8 d4 5d 04 14 33 c9 33 d2 e8 ?? ?? ?? ?? b8 ac 00 04 14 33 c9 33 d2 e8 ?? ?? ?? ?? b8 ac 82 02 14 33 c9 33 d2 } //2
		$a_01_2 = {53 50 59 5f 4e 45 54 5f 52 41 54 4d 55 54 45 58 } //1 SPY_NET_RATMUTEX
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}