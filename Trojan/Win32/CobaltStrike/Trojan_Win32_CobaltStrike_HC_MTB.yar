
rule Trojan_Win32_CobaltStrike_HC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.HC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e4 83 c0 01 89 45 e4 8b 4d e4 3b 4d b0 73 27 8b 55 e4 0f b6 8a ?? ?? ?? ?? 8b 45 e4 33 d2 be ?? ?? ?? ?? f7 f6 0f b6 54 15 ?? 33 ca 8b 45 f0 03 45 e4 88 08 eb } //10
		$a_01_1 = {5b 00 61 00 6e 00 74 00 69 00 6d 00 61 00 6c 00 77 00 61 00 72 00 65 00 5f 00 70 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 5d 00 20 00 3a 00 3a 00 20 00 57 00 65 00 72 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00 49 00 6d 00 70 00 6c 00 3a 00 3a 00 55 00 6e 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 57 00 65 00 72 00 28 00 29 00 } //1 [antimalware_provider] :: WerHandlerImpl::UnregisterWer()
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}