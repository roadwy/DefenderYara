
rule Trojan_AndroidOS_SpyBanker_G{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.G,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 62 61 6e 6b 31 32 2e 70 68 70 3f 6d 3d 41 70 69 26 61 3d 53 6d 73 26 69 6d 73 69 3d } //2 /bank12.php?m=Api&a=Sms&imsi=
		$a_01_1 = {7a 69 70 4e 50 4b 49 } //2 zipNPKI
		$a_01_2 = {6d 3d 41 70 69 26 61 3d 49 6e 64 65 78 26 62 61 6e 6b 3d } //2 m=Api&a=Index&bank=
		$a_01_3 = {26 72 65 63 65 72 74 70 77 3d } //2 &recertpw=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}