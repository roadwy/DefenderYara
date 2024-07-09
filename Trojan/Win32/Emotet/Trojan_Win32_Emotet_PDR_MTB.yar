
rule Trojan_Win32_Emotet_PDR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {25 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 45 ?? 8a 94 14 ?? ?? ?? ?? 32 c2 88 45 } //1
		$a_02_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 45 0f b6 94 14 ?? ?? ?? ?? 30 55 } //1
		$a_81_2 = {5a 7a 64 32 4c 4b 39 76 71 59 44 4c 79 57 76 72 5a 37 46 31 56 41 51 6d 74 36 4c 72 33 6f 31 4f 67 45 74 66 } //1 Zzd2LK9vqYDLyWvrZ7F1VAQmt6Lr3o1OgEtf
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}