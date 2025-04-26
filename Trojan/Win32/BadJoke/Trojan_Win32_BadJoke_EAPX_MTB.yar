
rule Trojan_Win32_BadJoke_EAPX_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.EAPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 8c 1d 78 56 fc ff 43 81 fb ?? ?? ?? ?? ?? ?? 8d 85 78 56 fc ff c7 85 44 56 fc ff 80 a9 03 00 89 85 40 56 fc ff 8d 85 40 56 fc ff } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}