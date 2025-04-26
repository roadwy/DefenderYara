
rule Trojan_Win32_Redline_CDP_MTB{
	meta:
		description = "Trojan:Win32/Redline.CDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 0c 03 55 fc 8a 02 88 45 fb 0f be 4d fb 0f be 75 fb 8b 45 fc 99 bf ?? ?? ?? ?? f7 ff 8b 45 08 0f be 04 10 69 c0 ?? ?? ?? ?? 6b c0 ?? 6b c0 ?? 99 bf ?? ?? ?? ?? f7 ff 83 e0 ?? 33 f0 03 ce } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}