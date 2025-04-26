
rule Trojan_Win32_CyptInject_YBR_MTB{
	meta:
		description = "Trojan:Win32/CyptInject.YBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 0c 10 8b 95 6c fd ff ff 03 95 ?? ?? ?? ?? 0f b6 02 33 c1 8b 8d ?? ?? ?? ?? 03 8d f4 f8 ff ff 88 01 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}