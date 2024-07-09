
rule Trojan_Win32_SpySnake_MM_MTB{
	meta:
		description = "Trojan:Win32/SpySnake.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 45 ff 0f b6 4d ff c1 f9 ?? 0f b6 55 ff c1 e2 ?? 0b ca 88 4d ff 0f b6 45 ff 33 45 f4 88 45 ff 0f b6 4d ff 81 e9 ?? ?? ?? ?? 88 4d ff 8b 55 ec 03 55 f4 8a 45 ff 88 02 e9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}