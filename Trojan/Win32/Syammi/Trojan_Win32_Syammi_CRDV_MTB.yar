
rule Trojan_Win32_Syammi_CRDV_MTB{
	meta:
		description = "Trojan:Win32/Syammi.CRDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 4c 02 18 8b 95 6c ff ff ff 03 95 98 fe ff ff 33 ca 88 4d fe 0f b7 85 5c ff ff ff 8b 4d d0 8d 54 01 22 2b 15 ?? ?? ?? ?? 83 c2 21 88 95 47 ff ff ff 0f b7 85 7c ff ff ff 83 e8 34 89 85 d8 fe ff ff e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}