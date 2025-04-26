
rule Trojan_Win64_CobaltStrikeLoader_LKAN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeLoader.LKAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 79 6e 63 2e 28 2a 52 48 65 30 55 63 64 70 48 45 76 29 2e 52 55 6e 6c 6f 63 6b } //1 sync.(*RHe0UcdpHEv).RUnlock
		$a_01_1 = {6e 58 30 6d 67 62 75 4f 6a 77 2e 28 2a 77 55 36 5f 58 66 76 34 29 2e 62 71 77 53 4f 76 72 35 6d } //1 nX0mgbuOjw.(*wU6_Xfv4).bqwSOvr5m
		$a_01_2 = {79 43 63 64 49 37 65 56 71 2e 28 2a 55 45 35 54 52 6c 29 2e 78 4b 46 58 70 55 35 43 79 61 62 } //1 yCcdI7eVq.(*UE5TRl).xKFXpU5Cyab
		$a_01_3 = {50 54 32 4d 74 56 52 39 67 72 35 2e 67 6f } //1 PT2MtVR9gr5.go
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}