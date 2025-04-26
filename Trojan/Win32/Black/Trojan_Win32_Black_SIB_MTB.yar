
rule Trojan_Win32_Black_SIB_MTB{
	meta:
		description = "Trojan:Win32/Black.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {57 0f b7 f7 59 90 18 5f 90 18 81 c7 ?? ?? ?? ?? [0-10] 33 db [0-10] ff 34 3b [0-10] 58 81 c0 ?? ?? ?? ?? [0-10] 81 f0 ?? ?? ?? ?? [0-10] 81 f0 ?? ?? ?? ?? 50 [0-10] 8f 04 1f [0-10] 83 eb ?? [0-10] 81 fb ?? ?? ?? ?? 90 18 [0-10] 90 18 ff 34 3b [0-10] 58 81 c0 90 1b 06 [0-10] 81 f0 90 1b 08 [0-10] 81 f0 ?? ?? ?? ?? 50 [0-10] 8f 04 1f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}