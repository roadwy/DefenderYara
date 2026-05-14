
rule Trojan_Win64_Lazy_SXK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.SXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 03 d2 66 8b 8c 45 ae fe ff ff 8b 45 8c 66 2b ca 66 03 [0-05] 66 89 8c 45 ae fe ff ff 8b 45 8c 40 89 45 8c 83 7d 8c } //30
		$a_03_1 = {8d 85 f0 fd ff ff c7 85 bc fd ff ff 00 00 00 00 89 85 c4 fd ff ff 8d 85 b4 fd ff ff c7 85 d0 fd ff ff 01 00 00 00 50 ff 15 ?? ?? ?? ?? 85 c0 75 2a } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}