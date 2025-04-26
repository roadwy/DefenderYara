
rule Trojan_Win64_Havokiz_AK_ibt{
	meta:
		description = "Trojan:Win64/Havokiz.AK!ibt,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 56 48 89 ce 53 48 83 ec 20 65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 8b 78 20 48 89 fb 0f b7 53 48 48 8b 4b 50 e8 85 ff ff ff 89 c0 48 39 f0 75 06 48 8b 43 20 eb 11 48 8b 1b 48 85 db 74 05 48 39 df 75 d9 48 83 c8 ff 48 83 c4 20 5b 5e 5f c3 41 57 49 89 d7 41 56 41 55 41 54 55 31 ed 57 56 53 48 89 cb 48 83 ec 28 48 63 41 3c 8b bc 08 88 00 00 00 48 01 cf 44 8b 77 20 44 8b 67 1c 44 8b 6f 24 49 01 ce 3b 6f 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}