
rule Trojan_Win32_Redline_GHJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 10 69 c0 ?? ?? ?? ?? 99 bf ?? ?? ?? ?? f7 ff 33 f0 83 f6 ?? 03 ce 8b 55 ?? 03 55 ?? 88 0a 0f be 45 ?? 8b 4d ?? 03 4d ?? 0f b6 11 2b d0 8b 45 ?? 03 45 ?? 88 10 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}