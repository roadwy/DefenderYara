
rule Trojan_Win32_Emotet_DSH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 8a 54 14 ?? 32 c2 88 03 } //1
		$a_81_1 = {4f 45 41 71 38 75 36 4a 74 41 7a 48 57 46 36 45 7a 55 70 49 66 35 67 58 4e 68 6d 45 58 37 48 } //1 OEAq8u6JtAzHWF6EzUpIf5gXNhmEX7H
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}