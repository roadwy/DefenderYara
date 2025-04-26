
rule Trojan_Win32_Badur_SNN_MTB{
	meta:
		description = "Trojan:Win32/Badur.SNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 85 c0 74 2d 6a 00 50 8d 85 ?? ?? ?? ?? 50 8d 8d 28 ff ff ff 51 e8 d1 06 00 00 8d 55 f0 52 68 00 10 00 00 8d 85 ?? ?? ?? ?? 50 56 ff d7 85 c0 75 cc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}