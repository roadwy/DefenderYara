
rule Trojan_Win32_KillFiles_CCIN_MTB{
	meta:
		description = "Trojan:Win32/KillFiles.CCIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8d 0c 3e 8b c6 46 f7 75 f4 8a 82 ?? ?? ?? ?? 8b 55 fc 32 04 0a 88 01 3b f3 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}