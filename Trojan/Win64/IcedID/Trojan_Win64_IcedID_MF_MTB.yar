
rule Trojan_Win64_IcedID_MF_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 4d 61 69 6e } //10 DllMain
		$a_01_1 = {57 5a 53 4b 64 32 4e 45 42 49 2e 64 6c 6c } //1 WZSKd2NEBI.dll
		$a_01_2 = {46 5a 4b 6c 57 66 4e 57 4e } //1 FZKlWfNWN
		$a_01_3 = {52 50 72 57 56 42 77 } //1 RPrWVBw
		$a_01_4 = {6b 43 58 6b 64 4b 74 61 64 57 } //1 kCXkdKtadW
		$a_01_5 = {70 52 4e 41 55 } //1 pRNAU
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win64_IcedID_MF_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 0f af 43 58 48 8b 83 a8 00 00 00 44 89 93 dc 00 00 00 41 8b d0 c1 ea 08 88 14 01 ff 43 5c 48 63 4b 5c 48 8b 83 a8 00 00 00 44 88 04 01 ff 43 5c 8b 8b e8 00 00 00 8b d1 44 8b 83 dc 00 00 00 41 2b d0 8b 43 38 41 03 d2 03 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedID_MF_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 20 48 83 c4 18 eb f4 48 83 7c 24 30 00 74 ed 48 8b 04 24 eb 4b 88 08 48 8b 04 24 66 3b ff 74 4b 48 8b 44 24 28 48 89 44 24 08 eb db 48 89 4c 24 08 48 83 ec 18 3a ff 74 0c } //5
		$a_01_1 = {75 69 66 6e 79 61 73 66 62 6a 61 75 69 6e 79 75 67 61 73 6a 61 73 } //5 uifnyasfbjauinyugasjas
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}