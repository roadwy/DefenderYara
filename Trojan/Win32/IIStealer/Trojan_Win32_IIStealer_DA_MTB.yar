
rule Trojan_Win32_IIStealer_DA_MTB{
	meta:
		description = "Trojan:Win32/IIStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {69 66 28 6e 61 76 69 67 61 74 6f 72 2e 75 73 65 72 41 67 65 6e 74 2e 74 6f 4c 6f 63 61 6c 65 4c 6f 77 65 72 43 61 73 65 28 29 2e 69 6e 64 65 78 4f 66 28 22 62 61 69 64 75 22 29 20 3d 3d 20 2d 31 29 7b 64 6f 63 75 6d 65 6e 74 2e 74 69 74 6c 65 } //1 if(navigator.userAgent.toLocaleLowerCase().indexOf("baidu") == -1){document.title
		$a_81_1 = {2e 72 65 70 6c 61 63 65 28 6e 65 77 20 52 65 67 45 78 70 28 } //1 .replace(new RegExp(
		$a_81_2 = {53 74 72 69 6e 67 2e 66 72 6f 6d 43 68 61 72 43 6f 64 65 28 } //1 String.fromCharCode(
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}