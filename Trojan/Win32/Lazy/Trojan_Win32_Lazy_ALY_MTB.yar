
rule Trojan_Win32_Lazy_ALY_MTB{
	meta:
		description = "Trojan:Win32/Lazy.ALY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 86 ?? ?? ?? ?? 50 68 ff 03 00 00 8d 46 08 50 6a fd 8d 85 e4 fd ff ff 50 6a 00 ff 33 } //3
		$a_03_1 = {ab ab ab ab 8d 85 e4 dd ff ff 50 ff 15 ?? ?? ?? ?? 68 e8 ce 55 00 8d 85 e4 dd ff ff 50 ff 15 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}