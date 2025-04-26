
rule Trojan_MacOS_PassSteal_A_MTB{
	meta:
		description = "Trojan:MacOS/PassSteal.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 9d 16 00 00 48 83 c4 30 0f 0b 48 8b 85 50 ff ff ff 48 89 45 c8 31 c0 89 c7 e8 f3 fd ff ff } //1
		$a_03_1 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 83 ff 00 0f 9c c0 a8 01 75 ?? 48 8b 4d f8 31 c0 48 39 c8 7c ?? 48 8b 3d 8f 4d 00 00 e8 ea 34 00 00 48 8b 05 83 4d 00 00 48 89 45 f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}