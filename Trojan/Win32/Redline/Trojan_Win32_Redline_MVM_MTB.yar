
rule Trojan_Win32_Redline_MVM_MTB{
	meta:
		description = "Trojan:Win32/Redline.MVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ff 8b 45 ?? 0f be 04 10 69 c0 ?? ?? ?? ?? 6b c0 ?? 6b c0 ?? 99 bf ?? ?? ?? ?? f7 ff 83 e0 ?? 33 f0 03 ce 8b 55 ?? 03 55 ?? 88 0a 0f be 45 ?? 8b 4d ?? 03 4d ?? 0f be 11 2b d0 8b 45 ?? 03 45 ?? 88 10 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}