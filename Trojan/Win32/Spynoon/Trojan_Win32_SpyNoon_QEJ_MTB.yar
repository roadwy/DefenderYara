
rule Trojan_Win32_SpyNoon_QEJ_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.QEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 00 20 00 2d 00 72 00 20 00 2d 00 68 00 70 00 5b 00 50 00 41 00 53 00 53 00 57 00 4f 00 52 00 44 00 5d 00 20 00 2d 00 76 00 5b 00 53 00 49 00 5a 00 45 00 5d 00 20 00 22 00 5b 00 4f 00 55 00 54 00 5f 00 50 00 41 00 54 00 5d 00 5c 00 5b 00 46 00 49 00 4c 00 45 00 4e 00 41 00 4d 00 45 00 5d 00 5f 00 5b 00 54 00 49 00 4d 00 45 00 5d 00 22 00 20 00 22 00 5b 00 49 00 4e 00 5f 00 50 00 41 00 54 00 48 00 5d 00 } //1 a -r -hp[PASSWORD] -v[SIZE] "[OUT_PAT]\[FILENAME]_[TIME]" "[IN_PATH]
		$a_03_1 = {f7 bd 30 fa ff ff 8a 82 ?? ?? ?? ?? 32 81 ?? ?? ?? ?? 88 84 0d f0 fb ff ff 8d 46 ff 99 f7 bd 30 fa ff ff 8a 82 ?? ?? ?? ?? 32 81 ?? ?? ?? ?? 88 84 0d f1 fb ff ff 8b c6 99 f7 bd 30 fa ff ff 8a 82 ?? ?? ?? ?? 32 86 ?? ?? ?? ?? 83 c6 04 88 84 3d ef fb ff ff 8b c7 99 f7 bd 30 fa ff ff 8a 82 ?? ?? ?? ?? 32 87 ?? ?? ?? ?? 83 c7 04 88 84 0d f3 fb ff ff 83 c1 04 81 fe 02 04 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}