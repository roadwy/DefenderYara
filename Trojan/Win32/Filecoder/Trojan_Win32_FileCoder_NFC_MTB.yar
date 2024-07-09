
rule Trojan_Win32_FileCoder_NFC_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.NFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {e8 fc 87 ff ff 48 89 c1 48 8d 41 ?? 89 59 0c c7 41 08 ?? ?? ?? ?? 66 85 f6 75 08 48 0f b7 35 ce 0f 18 00 66 89 71 04 66 c7 41 06 ?? ?? 8b cb c1 e9 ?? 03 cb c1 f9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}