
rule Trojan_Win32_FakeAV_NF_MTB{
	meta:
		description = "Trojan:Win32/FakeAV.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 95 cc f9 ff ff 8b 45 ec 01 d0 88 08 83 6d f4 02 83 45 f0 01 83 45 ec 01 eb ?? 8b 45 f0 8b 55 d0 } //3
		$a_03_1 = {83 7d f4 00 7e ?? 8b 45 ec 01 c0 0f b6 84 05 cc fb ff ff 0f be c0 c1 e0 04 89 c2 8b 45 ec } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}