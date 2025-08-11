
rule Ransom_Linux_Filecoder_AC_MTB{
	meta:
		description = "Ransom:Linux/Filecoder.AC!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 73 78 69 5f 65 6e 63 6f 64 65 72 } //1 main.esxi_encoder
		$a_01_1 = {6d 61 69 6e 2e 6c 6f 63 61 6c 5f 64 72 6f 70 5f 6e 6f 74 65 } //1 main.local_drop_note
		$a_01_2 = {6d 61 69 6e 2e 70 72 6f 67 72 65 73 73 5f 6c 6f 67 67 65 72 } //1 main.progress_logger
		$a_01_3 = {6d 61 69 6e 2e 69 73 5f 65 78 63 6c 75 64 65 5f 64 69 72 } //1 main.is_exclude_dir
		$a_01_4 = {6d 61 69 6e 2e 73 63 61 6e 5f 69 70 } //1 main.scan_ip
		$a_01_5 = {6d 61 69 6e 2e 72 65 6d 6f 74 65 5f 69 6e 69 74 } //1 main.remote_init
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}