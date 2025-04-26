
rule VirTool_Win32_CryptInject_YE_MTB{
	meta:
		description = "VirTool:Win32/CryptInject.YE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 93 03 45 99 89 45 c5 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 c1 8d 9d ?? fd ff ff 53 ff 55 c1 89 45 9d 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 cd 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 d1 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 c9 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 d5 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 d9 8d 9d ?? fd ff ff 53 ff 75 9d ff 55 c5 89 45 dd 8d 9d ?? fd ff ff 53 ff 55 c1 89 45 a1 8d 9d ?? fd ff ff 53 ff 75 a1 ff 55 c5 89 45 e1 8d 9d ?? fd ff ff 53 ff 75 a1 ff 55 c5 89 45 e5 8d 9d ?? fd ff ff 53 ff 75 a1 ff 55 c5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}