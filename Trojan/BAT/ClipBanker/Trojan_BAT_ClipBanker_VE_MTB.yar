
rule Trojan_BAT_ClipBanker_VE_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.VE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {62 76 73 64 76 64 73 73 64 } //1 bvsdvdssd
		$a_01_1 = {34 00 4c 00 49 00 46 00 45 00 42 00 55 00 4f 00 59 00 5f 00 4c 00 49 00 46 00 45 00 47 00 55 00 41 00 52 00 44 00 5f 00 4c 00 49 00 46 00 45 00 53 00 41 00 56 00 45 00 52 00 5f 00 53 00 41 00 46 00 45 00 54 00 59 00 5f 00 52 00 49 00 4e 00 47 00 5f 00 49 00 43 00 4f 00 4e 00 5f 00 31 00 39 00 31 00 35 00 35 00 32 00 } //1 4LIFEBUOY_LIFEGUARD_LIFESAVER_SAFETY_RING_ICON_191552
		$a_01_2 = {68 00 66 00 67 00 68 00 67 00 67 00 66 00 67 00 64 00 } //1 hfghggfgd
		$a_81_3 = {41 43 35 30 44 31 35 30 33 34 } //1 AC50D15034
		$a_81_4 = {4e 6f 6e 20 4f 62 66 75 73 63 61 74 65 64 } //1 Non Obfuscated
		$a_81_5 = {6d 53 56 66 67 4e 6a 55 59 52 6c 4d 6c 5a 51 69 4b 61 65 63 69 66 42 61 46 45 7a 66 42 41 39 7a 31 7a 56 48 } //1 mSVfgNjUYRlMlZQiKaecifBaFEzfBA9z1zVH
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}