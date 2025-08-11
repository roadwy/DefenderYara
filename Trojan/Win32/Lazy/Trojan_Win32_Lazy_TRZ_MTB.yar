
rule Trojan_Win32_Lazy_TRZ_MTB{
	meta:
		description = "Trojan:Win32/Lazy.TRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a ff 68 f0 87 0a 10 50 64 89 25 00 00 00 00 81 ec f0 02 00 00 33 c0 8a 88 ?? ?? ?? ?? 32 ca 42 88 4c 05 dd 81 e2 ff 00 00 80 79 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}